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
#include "securec.h"

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

DevAttestService::DevAttestService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{
}

DevAttestService::DevAttestService()
    : SystemAbility(DEVICE_ATTEST_PROFILE_SA_ID, true)
{
}

DevAttestService::~DevAttestService()
{
}

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

int32_t DevAttestService::CopyAttestResult(int32_t *resultArray, AttestResultInfo &attestResultInfo)
{
    if (resultArray == NULL) {
        return DEVATTEST_FAIL;
    }
    int32_t *head = resultArray;
    attestResultInfo.authResult_ = *head;
    head++;
    attestResultInfo.softwareResult_ = *head;
    for (int i = 0; i < SOFTWARE_RESULT_DETAIL_SIZE; i++) {
        attestResultInfo.softwareResultDetail_[i] = *(++head);
    }
    return DEVATTEST_SUCCESS;
}

int32_t DevAttestService::GetAttestStatus(AttestResultInfo &attestResultInfo)
{
    HILOGI("GetAttestStatus start");
    int32_t resultArraySize = MAX_ATTEST_RESULT_SIZE * sizeof(int32_t);
    int32_t *resultArray = (int32_t *)malloc(resultArraySize);
    if (resultArray == NULL) {
        HILOGE("malloc resultArray failed");
        return DEVATTEST_FAIL;
    }
    (void)memset_s(resultArray, resultArraySize, 0, resultArraySize);
    int32_t ticketLength = 0;
    char* ticketStr = NULL;
    int32_t ret = DEVATTEST_SUCCESS;
    do {
        ret = QueryAttest(&resultArray, MAX_ATTEST_RESULT_SIZE, &ticketStr, &ticketLength);
        if (ret != DEVATTEST_SUCCESS) {
            HILOGE("QueryAttest failed");
            break;
        }

        attestResultInfo.ticketLength_ = ticketLength;
        attestResultInfo.ticket_ = ticketStr;
        ret = CopyAttestResult(resultArray, attestResultInfo);
        if (ret != DEVATTEST_SUCCESS) {
            HILOGE("copy attest result failed");
            break;
        }
    } while (0);
    if (ticketStr != NULL && ticketLength != 0) {
        free(ticketStr);
        ticketStr = NULL;
    }
    free(resultArray);
    resultArray = NULL;
    HILOGI("GetAttestStatus end success");
    return ret;
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