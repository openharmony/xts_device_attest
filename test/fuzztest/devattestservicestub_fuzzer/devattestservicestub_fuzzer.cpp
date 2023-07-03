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

#include "devattestservicestub_fuzzer.h"

#include <string>
#include <securec.h>
#include "devattest_service_stub.h"

using namespace std;
using namespace OHOS::DevAttest;

namespace OHOS {
    const uint8_t *g_baseFuzzData = nullptr;
    size_t g_baseFuzzSize = 0;
    size_t g_baseFuzzPos;
    
    class DevattestServiceStubFuzz : public DevAttestServiceStub {
    public:
        DevattestServiceStubFuzz() = default;
        virtual ~DevattestServiceStubFuzz() = default;
        int32_t GetAttestStatus(AttestResultInfo &attestResultInfo) override
        {
            return 0;
        }
        void DelayUnloadTask() override
        {}
    };

    template <class T>
    T GetData()
    {
        T object{};
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

    static void OnRemoteRequest(const uint8_t* data, size_t size)
    {
        g_baseFuzzData = data;
        g_baseFuzzSize = size;
        g_baseFuzzPos = 0;
        uint32_t code = GetData<uint32_t>();
        MessageParcel datas;
        datas.WriteInterfaceToken(DevAttestServiceStub::GetDescriptor());
        datas.WriteBuffer(g_baseFuzzData + g_baseFuzzPos, g_baseFuzzSize - g_baseFuzzPos);
        datas.RewindRead(0);
        MessageParcel reply;
        MessageOption option;
        std::shared_ptr<DevAttestServiceStub> devattestservicestub = std::make_shared<DevattestServiceStubFuzz>();
        (void)devattestservicestub->OnRemoteRequest(code, datas, reply, option);
    }

    void DevattestServiceStubFuzzTest(const uint8_t* data, size_t size)
    {
        int32_t demandSize = sizeof(uint32_t);
        if (static_cast<int32_t>(size) >= demandSize) {
            OnRemoteRequest(data, size);
        }
        return;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DevattestServiceStubFuzzTest(data, size);
    return 0;
}
