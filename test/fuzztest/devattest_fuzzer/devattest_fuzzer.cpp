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

#include "devattest_fuzzer.h"

#include <string>
#include <securec.h>
#include <vector>
#include "devattest_client.h"

using namespace std;
using namespace OHOS::DevAttest;

namespace OHOS {
    constexpr int32_t SIZE = 4;
    static void GetAttestStatus(const uint8_t* data, size_t size)
    {
        AttestResultInfo attestResultInfo;
        int32_t testResult[1];
        if ((memcpy_s(testResult, sizeof(testResult), data, SIZE)) != EOK) {
            return;
        }

        for (int i = 0; i < SOFTWARE_RESULT_DETAIL_SIZE; i++) {
            attestResultInfo.softwareResultDetail_[i] = testResult[0];
        }
        attestResultInfo.authResult_ = testResult[0];
        attestResultInfo.softwareResult_ = testResult[0];
        attestResultInfo.ticketLength_ = testResult[0];
        attestResultInfo.ticket_ = std::string(data, data + size);
        DelayedSingleton<DevAttestClient>::GetInstance()->GetAttestStatus(attestResultInfo);
    }

    void DevattestClientFuzzTest(const uint8_t* data, size_t size)
    {
        if (static_cast<int32_t>(size) >= SIZE) {
            GetAttestStatus(data, size);
        }
        return;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DevattestClientFuzzTest(data, size);
    return 0;
}

