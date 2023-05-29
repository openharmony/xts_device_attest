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

#include "permission.h"

#include "accesstoken_kit.h"
#include "sys_mgr_client.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "devattest_log.h"

using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::Constants;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace DevAttest {
static bool IsTokenAplMatch(ATokenAplEnum apl)
{
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    pid_t pid = IPCSkeleton::GetCallingPid();
    pid_t uid = IPCSkeleton::GetCallingUid();
    ATokenTypeEnum type = AccessTokenKit::GetTokenTypeFlag(tokenId);
    HILOGD("[IsTokenAplMatch] checking apl, apl=%{public}d, type=%{public}d, pid=%{public}d, uid=%{public}d",
        static_cast<int32_t>(apl), static_cast<int32_t>(type), pid, uid);
    NativeTokenInfo info;
    AccessTokenKit::GetNativeTokenInfo(tokenId, info);
    if (info.apl == apl) {
        return true;
    }
    HILOGD("[IsTokenAplMatch] apl not match, info.apl=%{public}d, type=%{public}d, pid=%{public}d, uid=%{public}d",
        static_cast<int32_t>(info.apl), static_cast<int32_t>(type), pid, uid);
    return false;
}

Permission::Permission()
{
}

Permission::~Permission()
{
}

bool Permission::IsSystemCore()
{
    bool isMatch = IsTokenAplMatch(ATokenAplEnum::APL_SYSTEM_CORE);
    if (!isMatch) {
        HILOGE("[IsSystemCore] access token denied");
    }
    return isMatch;
}

bool Permission::IsSystemBasic()
{
    bool isMatch = IsTokenAplMatch(ATokenAplEnum::APL_SYSTEM_BASIC);
    if (!isMatch) {
        HILOGE("[IsSystemBasic] access token denied");
    }
    return isMatch;
}

bool Permission::IsSystemApl()
{
    return IsSystemBasic() || IsSystemCore();
}

void Permission::InitPermissionInterface()
{
    HILOGD("[InitPermissionInterface] begin");
    if (sptrBundleMgr_ != nullptr) {
        HILOGE("[InitPermissionInterface] already init");
        return;
    }

    sptrBundleMgr_ = GetBundleMgr();
    HILOGI("[InitPermissionInterface] success");
    return;
}

sptr<IBundleMgr> Permission::GetBundleMgr()
{
    auto bundleObj =
        DelayedSingleton<AppExecFwk::SysMrgClient>::GetInstance()->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleObj == nullptr) {
        HILOGE("[GetBundleMgr] GetSystemAbility is null");
        return nullptr;
    }

    sptr<AppExecFwk::IBundleMgr> bmgr = iface_cast<AppExecFwk::IBundleMgr>(bundleObj);
    if (bmgr == nullptr) {
        HILOGE("[GetBundleMgr] iface_cast get null");
    }
    return bmgr;
}

bool Permission::IsSystemHap()
{
    InitPermissionInterface();
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    pid_t pid = IPCSkeleton::GetCallingPid();
    pid_t uid = IPCSkeleton::GetCallingUid();
    ATokenTypeEnum type = AccessTokenKit::GetTokenTypeFlag(tokenId);
    HILOGD("[IsSystemHap] checking system hap, type=%{public}d, pid=%{public}d, uid=%{public}d",
        static_cast<int32_t>(type), pid, uid);
    bool result = false;
    switch (type) {
        case ATokenTypeEnum::TOKEN_HAP:
            if (sptrBundleMgr_ == nullptr) {
                HILOGE("[IsSystemHap] sptrBundleMgr_ is null");
                result = false;
                break;
            }
            result = sptrBundleMgr_->CheckIsSystemAppByUid(uid);
            break;
        case ATokenTypeEnum::TOKEN_NATIVE:
        case ATokenTypeEnum::TOKEN_SHELL:
            result = true;
            break;
        case ATokenTypeEnum::TOKEN_INVALID:
        case ATokenTypeEnum::TOKEN_TYPE_BUTT:
            break;
        default:
            break;
    }
    if (!result) {
        HILOGE("[IsSystemHap] system denied");
        return false;
    }
    return true;
}

bool Permission::IsSystem()
{
    return IsSystemApl() || IsSystemHap();
}

bool Permission::IsPermissionGranted(const std::string& perm)
{
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    pid_t pid = IPCSkeleton::GetCallingPid();
    pid_t uid = IPCSkeleton::GetCallingUid();
    ATokenTypeEnum type = AccessTokenKit::GetTokenTypeFlag(tokenId);
    HILOGD("[IsPermissionGranted] check permission, perm=%{public}s type=%{public}d, pid=%{public}d,uid=%{public}d",
        perm.c_str(), static_cast<int32_t>(type), pid, uid);
    int32_t result = PermissionState::PERMISSION_DENIED;
    switch (type) {
        case ATokenTypeEnum::TOKEN_HAP:
            result = AccessTokenKit::VerifyAccessToken(tokenId, perm);
            break;
        case ATokenTypeEnum::TOKEN_NATIVE:
        case ATokenTypeEnum::TOKEN_SHELL:
            result = PermissionState::PERMISSION_GRANTED;
            break;
        case ATokenTypeEnum::TOKEN_INVALID:
        case ATokenTypeEnum::TOKEN_TYPE_BUTT:
            break;
    }
    if (result == PermissionState::PERMISSION_DENIED) {
        HILOGE("[IsPermissionGranted] permis denied, perm=%{public}s type=%{public}d, pid=%{public}d, uid=%{public}d",
            perm.c_str(), static_cast<int32_t>(type), pid, uid);
        return false;
    }
    return true;
}

bool Permission::IsSystemHapPermGranted(const std::string& perm)
{
    return IsSystemHap() && IsPermissionGranted(perm);
}
} // namespace DevAttest
} // namespace OHOS
