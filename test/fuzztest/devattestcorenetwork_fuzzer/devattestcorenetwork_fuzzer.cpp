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

    static void ParseRespImpl(char* msgData)
    {
        if (msgData == nullptr) {
            return;
        }
        char* outputStr = nullptr;
        int32_t ret = ParseHttpsResp(msgData, &outputStr);
        if (ret != FUZZ_ATTEST_OK || outputStr == nullptr) {
            return;
        }
        free(outputStr);
        outputStr = nullptr;
        return;
    }

    static void ParseResp(const uint8_t* data, size_t size)
    {
        if (data == nullptr) {
            return;
        }
        size_t msgDataSize = size + 1;
        char* msgData = (char*)malloc(msgDataSize);
        if (msgData == nullptr) {
            return;
        }
        int32_t ret = memset_s(msgData, msgDataSize, 0, msgDataSize);
        if (ret != FUZZ_ATTEST_OK) {
            free(msgData);
            msgData = nullptr;
            return;
        }
        ret = memcpy_s(msgData, msgDataSize, data, size);
        if (ret != FUZZ_ATTEST_OK) {
            free(msgData);
            msgData = nullptr;
            return;
        }
        ParseRespImpl(msgData);
        free(msgData);
        msgData = nullptr;
        return;
    }

    void DevattestCoreNetworkFuzzTest(const uint8_t* data, size_t size)
    {
        int32_t demandSize = sizeof(uint32_t) + sizeof(char);
        if (static_cast<int32_t>(size) >= demandSize) {
            ParseResp(data, size);
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
