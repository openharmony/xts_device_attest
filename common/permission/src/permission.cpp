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
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "devattest_log.h"

using namespace OHOS;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace DevAttest {
Permission::Permission()
{
}

Permission::~Permission()
{
}

bool Permission::IsSystem()
{
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    pid_t pid = IPCSkeleton::GetCallingPid();
    pid_t uid = IPCSkeleton::GetCallingUid();
    ATokenTypeEnum type = AccessTokenKit::GetTokenTypeFlag(tokenId);
    HILOGD("[IsSystem] check permission, type=%{public}d, pid=%{public}d,uid=%{public}d",
        static_cast<int32_t>(type), pid, uid);
    bool result = false;
    switch (type) {
        case ATokenTypeEnum::TOKEN_HAP:
            result = TokenIdKit::IsSystemAppByFullTokenID(IPCSkeleton::GetCallingFullTokenID());
            break;
        case ATokenTypeEnum::TOKEN_NATIVE:
            HILOGD("[IsSystem] type switch in ATokenTypeEnum.TOKEN_NATIVE")
        case ATokenTypeEnum::TOKEN_SHELL:
            result = true;
            break;
        case ATokenTypeEnum::TOKEN_INVALID:
            HILOGD("[IsSystem] type switch in ATokenTypeEnum.TOKEN_INVALID")
        case ATokenTypeEnum::TOKEN_TYPE_BUTT:
            HILOGD("[IsSystem] type switch in ATokenTypeEnum.TOKEN_TYPE_BUTT")
            break;
    }
    if (!result) {
        HILOGE("[IsSystem] system denied, type=%{public}d, pid=%{public}d, uid=%{public}d",
            static_cast<int32_t>(type), pid, uid);
        return false;
    }
    return true;
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
            HILOGD("[IsPermissionGranted] type switch in ATokenTypeEnum.TOKEN_NATIVE")
        case ATokenTypeEnum::TOKEN_SHELL:
            result = PermissionState::PERMISSION_GRANTED;
            break;
        case ATokenTypeEnum::TOKEN_INVALID:
            HILOGD("[IsPermissionGranted] type switch in ATokenTypeEnum.TOKEN_INVALID")
        case ATokenTypeEnum::TOKEN_TYPE_BUTT:
            HILOGD("[IsPermissionGranted] type switch in ATokenTypeEnum.TOKEN_TYPE_BUTT")
            break;
    }
    if (result == PermissionState::PERMISSION_DENIED) {
        HILOGE("[IsPermissionGranted] permis denied, perm=%{public}s type=%{public}d, pid=%{public}d, uid=%{public}d",
            perm.c_str(), static_cast<int32_t>(type), pid, uid);
        return false;
    }
    return true;
}
} // namespace DevAttest
} // namespace OHOS
