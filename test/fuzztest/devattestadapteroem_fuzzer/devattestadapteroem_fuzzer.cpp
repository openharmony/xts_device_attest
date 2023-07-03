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

#include "devattestadapteroem_fuzzer.h"

#include <string>
#include <securec.h>
#include "attest_adapter_oem.h"

using namespace std;

namespace OHOS {
    constexpr int32_t OEM_TICKET_FUZZ = 0;
    constexpr int32_t OEM_AUTH_STATUS_FUZZ = 1;
    constexpr int32_t OEM_NETWORK_CONFIG_FUZZ = 2;
    constexpr int32_t OEM_AUTH_RESULT_CODE_FUZZ = 3;
    constexpr int32_t INTERFACE_NUM = 4;

    const uint8_t *g_baseFuzzData = nullptr;
    size_t g_baseFuzzSize = 0;
    size_t g_baseFuzzPos = 0;

    template <class T> T GetData()
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

    static void OEMWriteTicketData(const uint8_t* data, size_t size)
    {
        int32_t demandSize = sizeof(char) + sizeof(TicketInfo);
        if (static_cast<int32_t>(size) < demandSize) {
            return;
        }

        TicketInfo ticketInfo  = GetData<TicketInfo>();
        (void)OEMWriteTicket(&ticketInfo);
        return;
    }

    static void OEMWriteData(const uint8_t* data, size_t size, int32_t type)
    {
        uint32_t len  = GetData<uint32_t>();
        uint32_t remainSize = size - g_baseFuzzPos;
        len = (len > remainSize) ? remainSize : len;
 
        switch (type) {
            case OEM_AUTH_STATUS_FUZZ:
                (void)OEMWriteAuthStatus((char *)(data + g_baseFuzzPos), len);
                break;
            case OEM_NETWORK_CONFIG_FUZZ:
                (void)OEMWriteNetworkConfig((char *)(data + g_baseFuzzPos), len);
                break;
            case OEM_AUTH_RESULT_CODE_FUZZ:
                (void)OEMWriteAuthResultCode((char *)(data + g_baseFuzzPos), len);
                break;
            default:
                break;
        }
        return;
    }

    void DevattestAdapterOemFuzzTest(const uint8_t* data, size_t size)
    {
        g_baseFuzzData = data;
        g_baseFuzzSize = size;
        g_baseFuzzPos = 0;
        int32_t demandSize = sizeof(int32_t) + sizeof(char);
        if (static_cast<int32_t>(size) < demandSize) {
            return;
        }

        char randomId  = (GetData<char>() % INTERFACE_NUM);
        if (randomId == OEM_TICKET_FUZZ) {
            OEMWriteTicketData(data, size);
        } else {
            OEMWriteData(data, size, randomId);
        }
        return;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DevattestAdapterOemFuzzTest(data, size);
    return 0;
}
