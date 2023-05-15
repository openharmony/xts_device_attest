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
#include "notification_helper.h"
#include "notification_content.h"
#include "notification_normal_content.h"
#include "notification_request.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"
#include "iservice_registry.h"
#include "resource_manager.h"
#include "devattest_log.h"
#include "devattest_errno.h"
#include "attest_entry.h"

namespace OHOS {
namespace DevAttest {
using namespace OHOS;
using namespace OHOS::EventFwk;

constexpr std::int32_t DEVATTEST_PUBLISH_USERID = 0;
constexpr std::int32_t DEVATTEST_PUBLISH_NOTIFICATION_ID = 0;
const char* DEVATTEST_PUBLISH_BUNDLE = "com.ohos.settingsdata";
const char* DEVATTEST_CONTENT_TITLE = "ohos_desc_device_attest_publish_title";
const char* DEVATTEST_CONTENT_TEXT = "ohos_desc_device_attest_publish_text";

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
                PublishNotification();
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

void DevAttestNetworkCallback::PublishNotification(void)
{
    if (!isFirstPublish_) {
        HILOGE("[PublishNotification] Already publishNotification");
        return;
    }
    int32_t displayResult = DEVATTEST_INIT;
    int32_t ret = QueryAttestDisplayResult(&displayResult);
    if (ret == DEVATTEST_SUCCESS && displayResult == DEVATTEST_SUCCESS) {
        HILOGE("[PublishNotification] auth success");
        return;
    }

    ret = PublishNotificationImpl();
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("[PublishNotification] public notification fail");
        return;
    }

    isFirstPublish_ = false;
    HILOGI("[PublishNotification]publish notification success");
    return;
}

int32_t DevAttestNetworkCallback::PublishNotificationImpl(void)
{
    int32_t uid = 0;
    if (GetDevattestBundleUid(&uid) != DEVATTEST_SUCCESS) {
        HILOGE("[PublishNotificationImpl] failed to get uid");
        return DEVATTEST_FAIL;
    }

    Global::Resource::ResourceManager *resourceManager = Global::Resource::CreateResourceManager();
    if (resourceManager == nullptr) {
        HILOGE("[PublishNotificationImpl] get resourceManager failed");
        return DEVATTEST_FAIL;
    }
    std::string contentTitle;
    std::string contentText;
    Global::Resource::RState state = resourceManager->GetStringByName(DEVATTEST_CONTENT_TITLE, contentTitle);
    if (state != Global::Resource::RState::SUCCESS) {
        HILOGE("[PublishNotificationImpl] failed to get title form resource");
        return DEVATTEST_FAIL;
    }

    state = resourceManager->GetStringByName(DEVATTEST_CONTENT_TEXT, contentText);
    if (state != Global::Resource::RState::SUCCESS) {
        HILOGE("[PublishNotificationImpl] failed to get text form resource");
        return DEVATTEST_FAIL;
    }

    auto normalContent = std::make_shared<Notification::NotificationNormalContent>();
    if (normalContent == nullptr) {
        HILOGE("[PublishNotificationImpl] normalContent is null");
        return DEVATTEST_FAIL;
    }
    normalContent->SetTitle(contentTitle);
    normalContent->SetText(contentText);
    auto content = std::make_shared<Notification::NotificationContent>(normalContent);
    if (content == nullptr) {
        HILOGE("[PublishNotificationImpl] content is null");
        return DEVATTEST_FAIL;
    }
    Notification::NotificationRequest request;
    request.SetNotificationId(DEVATTEST_PUBLISH_NOTIFICATION_ID);
    request.SetCreatorUid(uid);
    request.SetContent(content);
    request.SetSlotType(Notification::NotificationConstant::OTHER);
    int32_t result = Notification::NotificationHelper::PublishNotification(request);
    if (result != DEVATTEST_SUCCESS) {
        HILOGE("[PublishNotificationImpl]publish result:%{public}d", result);
        return result;
    }
    return DEVATTEST_SUCCESS;
}

int32_t DevAttestNetworkCallback::GetDevattestBundleUid(int32_t* uid)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        return DEVATTEST_FAIL;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        return DEVATTEST_FAIL;
    }

    sptr<AppExecFwk::IBundleMgr> bundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (bundleMgr == nullptr) {
        return DEVATTEST_FAIL;
    }
    *uid = bundleMgr->GetUidByBundleName(std::string(DEVATTEST_PUBLISH_BUNDLE), DEVATTEST_PUBLISH_USERID);
    HILOGI("[GetDevattestBundleUid]uid:%{public}d", *uid);
    return DEVATTEST_SUCCESS;
}
} // DevAttest
} // OHOS

