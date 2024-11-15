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

#include "devattestservice_fuzzer.h"

#include <string>
#include <securec.h>
#include "devattest_service.h"

using namespace std;
using namespace OHOS::DevAttest;

namespace OHOS {
    const uint8_t *g_baseFuzzData = nullptr;
    size_t g_baseFuzzSize = 0;
    size_t g_baseFuzzPos;
        
    template <class T>
    T GetData()
    {
        T object {};
        size_t objectSize = sizeof(object);
        if (g_baseFuzzData == nullptr || objectSize > g_baseFuzzSize - g_baseFuzzPos) {
            return object;
        }
        errno_t ret = memcpy_s(&object, objectSize, g_baseFuzzData + g_baseFuzzPos, objectSize);
        if (ret != EOK) {
            return {};
        }
        g_baseFuzzPos += objectSize;
        return object;
    }

    static void GetAttestStatus(const uint8_t* data, size_t size)
    {
        g_baseFuzzData = data;
        g_baseFuzzSize = size;
        g_baseFuzzPos = 0;
        AttestResultInfo attestResultInfo;
        attestResultInfo.authResult_ = GetData<int32_t>();
        attestResultInfo.softwareResult_ = GetData<int32_t>();
        for (int i = 0; i < SOFTWARE_RESULT_DETAIL_SIZE; i++) {
            attestResultInfo.softwareResultDetail_[i] = GetData<int32_t>();
        }

        attestResultInfo.ticketLength_ = GetData<int32_t>();
        attestResultInfo.ticket_ = std::string(g_baseFuzzData + g_baseFuzzPos,
            g_baseFuzzData + size);
        DelayedSingleton<DevAttestService>::GetInstance()->GetAttestStatus(attestResultInfo);
    }

    void DevattestServiceFuzzTest(const uint8_t* data, size_t size)
    {
        int32_t demandSize = ((SOFTWARE_RESULT_DETAIL_SIZE + 3) * sizeof(int32_t));
        if (static_cast<int32_t>(size) >= demandSize) {
            GetAttestStatus(data, size);
        }
        return;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DevattestServiceFuzzTest(data, size);
    return 0;
}
