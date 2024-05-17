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

#include "devattest_client.h"

#include "iservice_registry.h"
#include "devattest_log.h"
#include "devattest_errno.h"
#include "devattest_profile_load_callback.h"

namespace OHOS {
namespace DevAttest {
using namespace std;
using namespace OHOS;
constexpr int32_t ATTEST_LOADSA_TIMEOUT_MS = 10000;

DevAttestClient &DevAttestClient::GetInstance()
{
    static DevAttestClient instance;
    return instance;
}

sptr<DevAttestInterface> DevAttestClient::GetDeviceProfileService()
{
    {
        std::lock_guard<std::mutex> lock(clientLock_);
        sptr<ISystemAbilityManager> samgrProxy =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            HILOGE("[GetDeviceProfileService] Failed to get system ability mgr.");
            return nullptr;
        }
        sptr<IRemoteObject> object =
            samgrProxy->CheckSystemAbility(DevAttestInterface::SA_ID_DEVICE_ATTEST_SERVICE);
        if (object != nullptr) {
            HILOGI("[GetDeviceProfileService] attestClientInterface currently exists");
            attestClientInterface_ = iface_cast<DevAttestInterface>(object);
            return attestClientInterface_;
        }
    }

    HILOGW("[GetDeviceProfileService] object is null");
    if (LoadDevAttestProfile()) {
        std::lock_guard<std::mutex> lock(clientLock_);
        if (attestClientInterface_ != nullptr) {
            return attestClientInterface_;
        } else {
            HILOGE("[GetDeviceProfileService] load devattest_service failed");
            return nullptr;
        }
    }
    HILOGE("[GetDeviceProfileService] load service failed");
    return nullptr;
}

bool DevAttestClient::LoadDevAttestProfile()
{
    std::unique_lock<std::mutex> lock(clientLock_);
    sptr<DevAttestProfileLoadCallback> loadCallback = new DevAttestProfileLoadCallback();
    if (loadCallback == nullptr) {
        HILOGE("[LoadDevAttestProfile] loadCallback is nullptr.");
        return false;
    }

    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        HILOGE("[LoadDevAttestProfile] Failed to get system ability mgr.");
        return false;
    }
    int32_t ret = samgr->LoadSystemAbility(DevAttestInterface::SA_ID_DEVICE_ATTEST_SERVICE, loadCallback);
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("[LoadDevAttestProfile] Failed to Load systemAbility");
        return false;
    }
    // 阻塞
    proxyConVar_.wait_for(lock, std::chrono::milliseconds(ATTEST_LOADSA_TIMEOUT_MS));
    return true;
}

void DevAttestClient::LoadSystemAbilitySuccess(const sptr<IRemoteObject> &remoteObject)
{
    std::unique_lock<std::mutex> lock(clientLock_);
    attestClientInterface_ = iface_cast<DevAttestInterface>(remoteObject);
    lock.unlock();
    proxyConVar_.notify_one();
    return;
}

void DevAttestClient::LoadSystemAbilityFail()
{
    std::unique_lock<std::mutex> lock(clientLock_);
    attestClientInterface_ = nullptr;
    lock.unlock();
    proxyConVar_.notify_one();
    return;
}

int DevAttestClient::GetAttestStatus(AttestResultInfo &attestResultInfo)
{
    sptr<DevAttestInterface> attestClientInterface = GetDeviceProfileService();
    if (attestClientInterface == nullptr) {
        HILOGE("[GetAttestStatus] DevAttestClient attestClientInterface is null");
        return DEVATTEST_FAIL;
    }
    int ret = attestClientInterface->GetAttestStatus(attestResultInfo);
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("[GetAttestStatus] DevAttestClient failed ret = %{public}d", ret);
        LoadSystemAbilityFail();
        return ret;
    }
    LoadSystemAbilityFail();
    return DEVATTEST_SUCCESS;
}
}
}