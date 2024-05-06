/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "devattest_network_callback.h"

#include <securec.h>
#include "singleton.h"
#include "devattest_log.h"
#include "devattest_errno.h"
#include "attest_entry.h"

namespace OHOS {
namespace DevAttest {
using namespace OHOS;
constexpr std::int32_t UNAVAILABLE_STATUS = 1;
constexpr std::int32_t AVAILABLE_STATUS = 2;
constexpr std::int32_t OTHER_STATUS = 3;
constexpr std::int32_t STATUS_MAX_COUNT = 30;
int32_t DevAttestNetworkCallback::NetCapabilitiesChange(
    sptr<NetHandle> &netHandle, const sptr<NetAllCapabilities> &netAllCap)
{
    if (netHandle == nullptr || netAllCap == nullptr) {
        HILOGW("[NetCapabilitiesChange] invalid parameter");
        return DEVATTEST_SUCCESS;
    }
    if (netStatus_ == AVAILABLE_STATUS) {
        HILOGW("[NetCapabilitiesChange] No need to operate");
        netStatus_ = OTHER_STATUS;
        return DEVATTEST_SUCCESS;
    }
    int32_t netHandleId = netHandle->GetNetId();
    if (netId_ == netHandleId) {
        HILOGI("[NetCapabilitiesChange] Skip the same operation");
        return DEVATTEST_SUCCESS;
    }
    netId_ = netHandleId;
    for (auto netCap : netAllCap->netCaps_) {
        switch (netCap) {
            case NET_CAPABILITY_MMS:
                HILOGD("[NetCapabilitiesChange] NET_CAPABILITY_MMS start");
                break;
            case NET_CAPABILITY_NOT_METERED:
                HILOGD("[NetCapabilitiesChange] NET_CAPABILITY_NOT_METERED start");
                break;
            case NET_CAPABILITY_INTERNET:
                HILOGD("[NetCapabilitiesChange] NET_CAPABILITY_INTERNET start");
                break;
            case NET_CAPABILITY_NOT_VPN:
                HILOGD("[NetCapabilitiesChange] NET_CAPABILITY_NOT_VPN start");
                break;
            case NET_CAPABILITY_VALIDATED:
                HILOGD("[NetCapabilitiesChange] NET_CAPABILITY_VALIDATED start");
                (void)AttestTask();
                break;
            case NET_CAPABILITY_PORTAL:
                HILOGD("[NetCapabilitiesChange] NET_CAPABILITY_PORTAL start");
                break;
            default:
                HILOGD("[NetCapabilitiesChange] default start");
                break;
        }
    }
    return DEVATTEST_SUCCESS;
}

int32_t DevAttestNetworkCallback::NetAvailable(sptr<NetHandle> &netHandle)
{
    netStatus_ += AVAILABLE_STATUS;
    if (netStatus_ > STATUS_MAX_COUNT) {
        netStatus_ = OTHER_STATUS;
    }
    (void)AttestCreateTimerTask();
    return DEVATTEST_SUCCESS;
}

int32_t DevAttestNetworkCallback::NetUnavailable(void)
{
    netStatus_ += UNAVAILABLE_STATUS;
    if (netStatus_ > STATUS_MAX_COUNT) {
        netStatus_ = OTHER_STATUS;
    }
    return DEVATTEST_SUCCESS;
}
} // DevAttest
} // OHOS

