/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "devattest_notification_publish.h"

#include <cstdint>
#include <securec.h>
#include "notification_helper.h"
#include "notification_content.h"
#include "notification_request.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "locale_config.h"
#include "devattest_log.h"
#include "devattest_errno.h"
#include "attest_entry.h"

namespace OHOS {
namespace DevAttest {
using namespace OHOS;
using namespace OHOS::EventFwk;
using namespace std;
using namespace AppExecFwk;

constexpr std::int32_t INVALID_UID = -1;
constexpr std::int32_t LOCALE_ITEM_SIZE = 5;
constexpr std::int32_t PARAM_THREE = 3;
constexpr std::int32_t DEVATTEST_PUBLISH_NOTIFICATION_ID = 0;
const char* DEVATTEST_PUBLISH_BUNDLE = "com.ohos.settingsdata";
const char* DEVATTEST_SETTINGS_BUNDLE = "com.ohos.settings";
const char* DEVATTEST_CONTENT_TITLE = "OpenHarmony_Compatibility_Assessment";
const char* DEVATTEST_CONTENT_TEXT = "assessmentPassFailedText";

DevAttestNotificationPublish::DevAttestNotificationPublish()
{
}

DevAttestNotificationPublish::~DevAttestNotificationPublish()
{
}

void DevAttestNotificationPublish::PublishNotification(void)
{
    int32_t publishable = DEVATTEST_INIT;
    int32_t ret = QueryAttestPublishable(&publishable);
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("[PublishNotification] QueryAttestPublishable fail");
        return;
    }
    if (publishable != DEVATTEST_SUCCESS) {
        HILOGE("[PublishNotification] No need to publish notifications");
        return;
    }

    ret = PublishNotificationImpl();
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("[PublishNotification] public notification fail");
        return;
    }
    AttestPublishComplete();
    HILOGI("[PublishNotification] publish notification success");
    return;
}

int32_t DevAttestNotificationPublish::PublishNotificationImpl(void)
{
    int32_t uid = 0;
    std::string settingsHapPath;
    std::string contentTitle;
    std::string contentText;
    if (GetDevattestBundleUid(&uid) != DEVATTEST_SUCCESS) {
        HILOGE("[PublishNotificationImpl] failed to get uid");
        return DEVATTEST_FAIL;
    }

    if (GetDevattestHapPath(settingsHapPath) != DEVATTEST_SUCCESS) {
        HILOGE("[PublishNotificationImpl] failed to get hap path");
        return DEVATTEST_FAIL;
    }

    if (GetDevattestContent(contentTitle, contentText, settingsHapPath) != DEVATTEST_SUCCESS) {
        HILOGE("[PublishNotificationImpl] failed to get Content");
        return DEVATTEST_FAIL;
    }

    shared_ptr<Notification::NotificationNormalContent> normalContent =
        std::make_shared<Notification::NotificationNormalContent>();
    if (normalContent == nullptr) {
        HILOGE("[PublishNotificationImpl] normalContent is null");
        return DEVATTEST_FAIL;
    }
    normalContent->SetTitle(contentTitle);
    normalContent->SetText(contentText);
    shared_ptr<Notification::NotificationContent> content =
        std::make_shared<Notification::NotificationContent>(normalContent);
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
        HILOGE("[PublishNotificationImpl] publish result:%{public}d", result);
        return result;
    }
    return DEVATTEST_SUCCESS;
}

sptr<IBundleMgr> DevAttestNotificationPublish::GetBundleMgr(void)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        HILOGE("[GetBundleMgr] get systemAbilityManager failed");
        return nullptr;
    }
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        HILOGE("[GetBundleMgr] get remoteObject failed");
        return nullptr;
    }
    sptr<IBundleMgr> bundleMgr = iface_cast<IBundleMgr>(remoteObject);
    if (bundleMgr == nullptr) {
        HILOGE("[GetBundleMgr] get bundleMgr failed");
        return nullptr;
    }
    return bundleMgr;
}

int32_t DevAttestNotificationPublish::GetDevattestBundleUid(int32_t* uid)
{
    int32_t userId = -1;
    int32_t ret = OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("[GetDevattestBundleUid] GetOsAccountLocalIdFromProcess failed, ret:%{public}d", ret);
        return DEVATTEST_FAIL;
    }
    sptr<IBundleMgr> bundleMgr = GetBundleMgr();
    if (bundleMgr == nullptr) {
        HILOGE("[GetDevattestBundleUid] GetBundleMgr failed");
        return DEVATTEST_FAIL;
    }
    *uid = bundleMgr->GetUidByBundleName(std::string(DEVATTEST_PUBLISH_BUNDLE), userId);
    if (*uid == INVALID_UID) {
        HILOGE("[GetDevattestBundleUid] GetUidByBundleName failed");
        return DEVATTEST_FAIL;
    }
    return DEVATTEST_SUCCESS;
}

int32_t DevAttestNotificationPublish::GetDevattestHapPath(std::string &settingsHapPath)
{
    sptr<IBundleMgr> bundleMgr = GetBundleMgr();
    if (bundleMgr == nullptr) {
        HILOGE("[GetDevattestHapPath] GetBundleMgr failed");
        return DEVATTEST_FAIL;
    }
    std::vector<int32_t> ids;
    int32_t ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("[GetDevattestHapPath] QueryActiveOsAccountIds failed, ret:%{public}d", ret);
        return DEVATTEST_FAIL;
    }
    BundleInfo bundleInfo;
    ret = DEVATTEST_FAIL;
    for (int32_t id : ids) {
        if (bundleMgr->GetBundleInfo(DEVATTEST_SETTINGS_BUNDLE, GET_BUNDLE_WITH_EXTENSION_INFO, bundleInfo, id)) {
            ret = DEVATTEST_SUCCESS;
            break;
        }
    }
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("[GetDevattestHapPath] GetBundleInfo failed");
        return DEVATTEST_FAIL;
    }
    for (HapModuleInfo hapModuleInfo : bundleInfo.hapModuleInfos) {
        std::string moduleResPath = hapModuleInfo.hapPath.empty() ? hapModuleInfo.resourcePath : hapModuleInfo.hapPath;
        if (!moduleResPath.empty()) {
            settingsHapPath = moduleResPath;
        }
    }
    if (settingsHapPath.empty()) {
        HILOGE("[GetDevattestHapPath] get setiingsHapPath failed");
        return DEVATTEST_FAIL;
    }
    return DEVATTEST_SUCCESS;
}

std::shared_ptr<Global::Resource::ResConfig> DevAttestNotificationPublish::GetDevattestResConfig(void)
{
    std::shared_ptr<Global::Resource::ResConfig> pResConfig(Global::Resource::CreateResConfig());

    string localeStr = Global::I18n::LocaleConfig::GetSystemLocale();
    if (localeStr.empty()) {
        HILOGE("[GetDevattestResConfig] failed to GetSystemLocale");
        return nullptr;
    }

    char language[LOCALE_ITEM_SIZE] = {0};
    char script[LOCALE_ITEM_SIZE] = {0};
    char region[LOCALE_ITEM_SIZE] = {0};
    // zh-Hans-CN
    int32_t ret = sscanf_s(localeStr.c_str(), "%[a-zA-Z]-%[a-zA-Z]-%[a-zA-Z]",
        language, LOCALE_ITEM_SIZE,
        script, LOCALE_ITEM_SIZE,
        region, LOCALE_ITEM_SIZE);
    if (ret != PARAM_THREE) {
        HILOGE("[GetDevattestResConfig] failed to split locale locale:%{public}s", localeStr.c_str());
        return nullptr;
    }

    Global::Resource::RState state = pResConfig->SetLocaleInfo(language, script, region);
    if (state != Global::Resource::RState::SUCCESS) {
        HILOGE("[GetDevattestResConfig] failed to SetLocaleInfo state:%{public}d", state);
        return nullptr;
    }
    return pResConfig;
}

int32_t DevAttestNotificationPublish::GetDevattestContent(std::string &title, std::string &text, std::string &settingsHapPath)
{
    std::shared_ptr<Global::Resource::ResourceManager> pResMgr(Global::Resource::CreateResourceManager());
    if (pResMgr == nullptr) {
        HILOGE("[GetDevattestContent] get resourceManager failed");
        return DEVATTEST_FAIL;
    }

    if (!pResMgr->AddResource(settingsHapPath.c_str())) {
        HILOGE("[GetDevattestContent] failed to AddResource");
        return DEVATTEST_FAIL;
    }

    std::shared_ptr<Global::Resource::ResConfig> pResConfig = GetDevattestResConfig();
    Global::Resource::RState state = pResMgr->UpdateResConfig(*pResConfig);
    if (state != Global::Resource::RState::SUCCESS) {
        HILOGE("[GetDevattestContent] failed to UpdateResConfig state:%{public}d", state);
        return DEVATTEST_FAIL;
    }

    state = pResMgr->GetStringByName(DEVATTEST_CONTENT_TITLE, title);
    if (state != Global::Resource::RState::SUCCESS) {
        HILOGE("[GetDevattestContent] failed to get title form resource state:%{public}d", state);
        return DEVATTEST_FAIL;
    }

    state = pResMgr->GetStringByName(DEVATTEST_CONTENT_TEXT, text);
    if (state != Global::Resource::RState::SUCCESS) {
        HILOGE("[GetDevattestContent] failed to get text form resource state:%{public}d", state);
        return DEVATTEST_FAIL;
    }
    return DEVATTEST_SUCCESS;
}
} // DevAttest
} // OHOS

