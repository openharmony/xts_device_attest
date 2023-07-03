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

#include "devattestnetworkcallback_fuzzer.h"

#include <string>
#include <securec.h>
#include "devattest_network_callback.h"

using namespace std;
using namespace OHOS::DevAttest;
using namespace OHOS::NetManagerStandard;
namespace OHOS {
    const uint8_t *g_baseFuzzData = nullptr;
    size_t g_baseFuzzSize = 0;
    size_t g_baseFuzzPos;
    std::vector<NetCap> netCaps = {NET_CAPABILITY_MMS, NET_CAPABILITY_NOT_METERED, NET_CAPABILITY_INTERNET,
                                   NET_CAPABILITY_NOT_VPN, NET_CAPABILITY_VALIDATED, NET_CAPABILITY_CAPTIVE_PORTAL,
                                   NET_CAPABILITY_INTERNAL_DEFAULT};

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

    static void NetCapabilitiesChange(const uint8_t* data, size_t size)
    {
        g_baseFuzzData = data;
        g_baseFuzzSize = size;
        g_baseFuzzPos = 0;
        uint32_t netId = GetData<uint32_t>();
        sptr<NetHandle> handle = (std::make_unique<NetHandle>()).release();
        handle->SetNetId(netId);
        sptr<NetAllCapabilities> allCap = (std::make_unique<NetAllCapabilities>()).release();
        for (NetCap netCap : netCaps) {
            if (GetData<bool>()) {
                allCap->netCaps_.insert(netCap);
            }
        }
        sptr<DevAttestNetworkCallback> devattestnetworkcallback = (std::make_unique<DevAttestNetworkCallback>()).release();
        (void)devattestnetworkcallback->NetCapabilitiesChange(handle, allCap);
    }

    void DevattestNetworkCallbackFuzzTest(const uint8_t* data, size_t size)
    {
        int32_t demandSize = sizeof(int32_t) + sizeof(char);
        if (static_cast<int32_t>(size) >= demandSize) {
            NetCapabilitiesChange(data, size);
        }
        return;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DevattestNetworkCallbackFuzzTest(data, size);
    return 0;
}
