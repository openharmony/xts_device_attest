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

#include "devattest_service.h"

#include <map>
#include <string>
#include <iostream>

#include "cstdint"

#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"
#include "iservice_registry.h"

#include "net_conn_client.h"
#include "net_conn_constants.h"

#include "devattest_errno.h"
#include "devattest_log.h"
#include "devattest_system_ability_listener.h"
#include "attest_result_info.h"
#include "attest_entry.h"

using namespace std;
namespace OHOS {
namespace DevAttest {
REGISTER_SYSTEM_ABILITY_BY_ID(DevAttestService, DEVICE_ATTEST_PROFILE_SA_ID, true)

void DevAttestService::OnStart()
{
    HILOGI("DevAttestService OnStart");
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        HILOGI("DevAttest Service has already started.");
        return;
    }
    if (!Init()) {
        HILOGE("Failed to init DevAttestService.");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    HILOGI("DevAttestService start success");
    sptr<DevAttestSystemAbilityListener> devAttestSystemAbilityListener =
        (std::make_unique<DevAttestSystemAbilityListener>()).release();
    if (!devAttestSystemAbilityListener->AddDevAttestSystemAbilityListener(NETMANAGER_SAMGR_ID)) {
        HILOGE("AddDevAttestSystemAbilityListener failed.");
    }
}
bool DevAttestService::Init()
{
    HILOGI("DevAttestService Init begin");
    if (!registerToSa_) {
        bool ret = Publish(this);
        if (!ret) {
            HILOGE("DevAttestService Init Publish failed");
            return false;
        }
        registerToSa_ = true;
    }
    HILOGI("DevAttestService Init Success");
    return true;
}
void DevAttestService::OnStop()
{
    HILOGI("DevAttestService OnStop Begin");
    state_ = ServiceRunningState::STATE_NOT_START;
    registerToSa_ = false;
}
int DevAttestService::GetAttestStatus(AttestResultInfo &attestResultInfo)
{
    char* ticketStr = NULL;
    int authRes = QueryAttest(&attestResultInfo.authResult_, &attestResultInfo.softwareResult_, &ticketStr); 
    if (authRes == DEVATTEST_SUCCESS) {
        attestResultInfo.ticket_ = ticketStr;
    }
    HILOGI("GetAttestStatus end success %{public}d", authRes);
    return authRes;
}
// 根据入参判断接口权限，当前没有入参，后续确认不需要后再删除
bool DevAttestService::CheckPermission(const std::string &packageName)
{
    HILOGI("DevAttestService CheckPermission packageName %{public}s", packageName.c_str());
    if (packageName.empty()) {
        HILOGE("CheckPermission param is null");
        return false;
    }
    return true;
}
} // end of DevAttest
} // end of OHOS