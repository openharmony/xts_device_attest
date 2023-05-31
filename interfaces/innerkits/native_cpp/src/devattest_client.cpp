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
constexpr int32_t DP_LOADSA_TIMEOUT_MS = 10000;
DevAttestClient::DevAttestClient()
{
}

DevAttestClient::~DevAttestClient()
{
}

sptr<DevAttestInterface> DevAttestClient::GetDeviceProfileService()
{
    {
        std::lock_guard<std::mutex> lock(clientLock_);
        if (attestClientInterface_ != nullptr) {
            return attestClientInterface_;
        }
        sptr<ISystemAbilityManager> samgrProxy =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            HILOGE("[GetDeviceProfileService]Failed to get system ability mgr.");
            return nullptr;
        }
        sptr<IRemoteObject> object =
            samgrProxy->CheckSystemAbility(DevAttestInterface::SA_ID_DEVICE_ATTEST_SERVICE);
        if (object != nullptr) {
            HILOGI("[GetDeviceProfileService]get service succeeded");
            attestClientInterface_ = iface_cast<DevAttestInterface>(object);
            return attestClientInterface_;
        }
    }

    HILOGW("[GetDeviceProfileService]object is null");
    if (LoadDevAttestProfile()) {
        std::lock_guard<std::mutex> lock(clientLock_);
        if (attestClientInterface_ != nullptr) {
            return attestClientInterface_;
        } else {
            HILOGE("[GetDeviceProfileService]load devattest_service failed");
            return nullptr;
        }
    }
    HILOGE("[GetDeviceProfileService]load service failed");
    return nullptr;
}

bool DevAttestClient::LoadDevAttestProfile()
{
    std::unique_lock<std::mutex> lock(clientLock_);
    sptr<DevAttestProfileLoadCallback> loadCallback = new DevAttestProfileLoadCallback();
    if (loadCallback == nullptr) {
        HILOGE("loadCallback is nullptr.");
        return false;
    }

    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        HILOGE("Failed to get system ability mgr.");
        return false;
    }
    int32_t ret = samgr->LoadSystemAbility(DevAttestInterface::SA_ID_DEVICE_ATTEST_SERVICE, loadCallback);
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("Failed to Load systemAbility");
        return false;
    }
    // 阻塞
    bool waitStatus = proxyConVar_.wait_for(lock, std::chrono::milliseconds(DP_LOADSA_TIMEOUT_MS),
        [this]() { return attestClientInterface_ != nullptr; });
    if (!waitStatus) {
        HILOGE("dp load sa timeout");
        return false;
    }
    return true;
}

void DevAttestClient::LoadSystemAbilitySuccess(const sptr<IRemoteObject> &remoteObject)
{
    std::lock_guard<std::mutex> lock(clientLock_);
    if (remoteObject == nullptr) {
        return;
    }
    attestClientInterface_ = iface_cast<DevAttestInterface>(remoteObject);
    proxyConVar_.notify_one();
    return;
}

void DevAttestClient::LoadSystemAbilityFail()
{
    std::lock_guard<std::mutex> lock(clientLock_);
    attestClientInterface_ = nullptr;
    return;
}

int DevAttestClient::GetAttestStatus(AttestResultInfo &attestResultInfo)
{
    sptr<DevAttestInterface> attestClientInterface = GetDeviceProfileService();
    if (attestClientInterface == nullptr) {
        HILOGE("[GetAttestStatus]DevAttestClient attestClientInterface is null");
        return DEVATTEST_FAIL;
    }
    int ret = attestClientInterface->GetAttestStatus(attestResultInfo);
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("[GetAttestStatus]DevAttestClient failed ret = %{public}d", ret);
        return ret;
    }
    return DEVATTEST_SUCCESS;
}
}
}