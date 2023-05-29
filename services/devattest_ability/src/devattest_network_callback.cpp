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

#include "cstdint"

#include "net_conn_client.h"
#include "net_conn_constants.h"

#include "devattest_log.h"
#include "devattest_errno.h"
#include "attest_entry.h"

namespace OHOS {
namespace DevAttest {
using namespace OHOS;
int32_t DevAttestNetworkCallback::NetCapabilitiesChange(
    sptr<NetHandle> &netHandle, const sptr<NetAllCapabilities> &netAllCap)
{
    if (netHandle == nullptr || netAllCap == nullptr) {
        HILOGI("[NetCapabilitiesChange] invalid parameter");
        return DEVATTEST_SUCCESS;
    }
    int32_t ret = DEVATTEST_SUCCESS;
    int32_t netHandleId = netHandle->GetNetId();
    if (netId_ == netHandleId) {
        HILOGI("[NetCapabilitiesChange] Skip the same operation");
        return DEVATTEST_SUCCESS;
    }
    netId_ = netHandleId;
    for (auto netCap : netAllCap->netCaps_) {
        switch (netCap) {
            case NET_CAPABILITY_MMS:
                HILOGI("[NetCapabilitiesChange] NET_CAPABILITY_MMS start");
                break;
            case NET_CAPABILITY_NOT_METERED:
                HILOGI("[NetCapabilitiesChange] NET_CAPABILITY_NOT_METERED start");
                break;
            case NET_CAPABILITY_INTERNET:
                HILOGI("[NetCapabilitiesChange] NET_CAPABILITY_INTERNET start");
                ret = AttestTask();
                HILOGI("DevAttestService test success, ret = %{public}d", ret);
                break;
            case NET_CAPABILITY_NOT_VPN:
                HILOGI("[NetCapabilitiesChange] NET_CAPABILITY_NOT_VPN start");
                break;
            case NET_CAPABILITY_VALIDATED:
                HILOGI("[NetCapabilitiesChange] NET_CAPABILITY_VALIDATED start");
                break;
            case NET_CAPABILITY_CAPTIVE_PORTAL:
                HILOGI("[NetCapabilitiesChange] NET_CAPABILITY_CAPTIVE_PORTAL start");
                break;
            default:
                HILOGI("[NetCapabilitiesChange] default start");
                break;
        }
    }
    return DEVATTEST_SUCCESS;
}
} // DevAttest
} // OHOS

