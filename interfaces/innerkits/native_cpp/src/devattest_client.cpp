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

#include "system_ability_definition.h"

#include "iservice_registry.h"

#include "devattest_log.h"
#include "devattest_errno.h"
#include "attest_result_info.h"

using namespace std;
using namespace OHOS;

namespace OHOS {
namespace DevAttest {
DevAttestClient::DevAttestClient()
{
    (void)InitClientService();
}

DevAttestClient::~DevAttestClient()
{
}

int DevAttestClient::InitClientService()
{
    HILOGI("DevAttestClient InitClientService begin");
    if (attestClientInterface_ != nullptr) {
        HILOGI("DevAttestClient InitClientService already init");
        return DEVATTEST_SUCCESS;
    }

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!samgr) {
        HILOGE("Failed to get system ability mgr.");
        return DEVATTEST_SA_NO_INIT;
    }

    auto object = samgr->CheckSystemAbility(DEVICE_ATTEST_PROFILE_SA_ID);
    if (!object) {
        HILOGE("Failed to get Device Attest.");
        return DEVATTEST_SA_NO_INIT;
    }
    attestClientInterface_ = iface_cast<DevAttestInterface>(object);
    HILOGI("DevAttestClient InitClientService success");
    return DEVATTEST_SUCCESS;
}

int DevAttestClient::GetAttestStatus(AttestResultInfo &attestResultInfo)
{
    HILOGI("DevAttestClient GetAttestStatus Begin");
    if (attestClientInterface_ == nullptr) {
        HILOGE("DevAttestClient GetAttestStatus attestClientInterface_ is null");
        return DEVATTEST_FAIL;
    }
    int ret = attestClientInterface_->GetAttestStatus(attestResultInfo);
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("DevAttestClient GetAttestStatus failed ret = %{public}d", ret);
        return ret;
    }
    HILOGI("DevAttestClient GetAttestStatus end");
    return DEVATTEST_SUCCESS;
}
}
}