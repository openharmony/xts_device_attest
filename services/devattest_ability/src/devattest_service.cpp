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

#include <string>
#include <iostream>
#include <cstdint>
#include <securec.h>
#include "iservice_registry.h"
#include "devattest_errno.h"
#include "devattest_log.h"
#include "devattest_system_ability_listener.h"
#include "devattest_task.h"
#include "attest_entry.h"
#include "devattest_network_manager.h"

namespace OHOS {
namespace DevAttest {
using namespace std;
constexpr int32_t UNLOAD_IMMEDIATELY = 0;
constexpr int32_t DELAY_TIME = 300000;
const char* ATTEST_UNLOAD_TASK_ID = "attest_unload_task";
REGISTER_SYSTEM_ABILITY_BY_ID(DevAttestService, DevAttestInterface::SA_ID_DEVICE_ATTEST_SERVICE, false)

DevAttestService::DevAttestService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{
}

DevAttestService::DevAttestService()
    : SystemAbility(SA_ID_DEVICE_ATTEST_SERVICE, false)
{
}

DevAttestService::~DevAttestService()
{
}

void DevAttestService::OnStart(const SystemAbilityOnDemandReason& startReason)
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        HILOGE("[OnStart] DevAttest Service has already started.");
        return;
    }
    if (!Init()) {
        HILOGE("[OnStart] Failed to init DevAttestService.");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    HILOGI("[OnStart] DevAttestService start success");
    if (startReason.GetId() != OHOS::OnDemandReasonId::INTERFACE_CALL) {
        DevAttestTask devAttestTask;
        if (!devAttestTask.CreateThread()) {
            HILOGE("[OnStart] Failed to CreateThread");
        }
    } else {
        sptr<DevAttestSystemAbilityListener> pListener =
            (std::make_unique<DevAttestSystemAbilityListener>()).release();
        if (!pListener->AddDevAttestSystemAbilityListener(COMM_NET_CONN_MANAGER_SYS_ABILITY_ID)) {
            HILOGE("[OnStart] AddDevAttestSystemAbilityListener failed.");
        }
    }
    return;
}

bool DevAttestService::Init()
{
    shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create(ATTEST_UNLOAD_TASK_ID);
    if (unloadHandler_ == nullptr) {
        unloadHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    if (unloadHandler_ == nullptr) {
        return false;
    }

    if (!registerToSa_) {
        bool ret = Publish(this);
        if (!ret) {
            HILOGE("[OnStart] DevAttestService Init Publish failed");
            return false;
        }
        registerToSa_ = true;
    }
    return true;
}

void DevAttestService::OnStop()
{
    HILOGI("[OnStop] DevAttestService OnStop");
    state_ = ServiceRunningState::STATE_NOT_START;
    registerToSa_ = false;
}

int32_t DevAttestService::OnIdle(const SystemAbilityOnDemandReason& idleReason)
{
    HILOGI("[OnIdle] reason %{public}d", idleReason.GetId());
    (void)DelayedSingleton<DevAttestNetworkManager>::GetInstance()->UnregisterNetConnCallback();
    (void)AttestDestroyTimerTask;
    AttestWaitTaskOver();
    return UNLOAD_IMMEDIATELY;
}

void DevAttestService::DelayUnloadTask(void)
{
    HILOGI("delay unload task begin");
    if (unloadHandler_ == nullptr) {
        HILOGE("can not carry out the delayed unload task");
        shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create(ATTEST_UNLOAD_TASK_ID);
        unloadHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
        return;
    }
    auto task = []() {
        sptr<ISystemAbilityManager> samgrProxy =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            HILOGE("[unload] samgrProxy is null");
            return;
        }
        int32_t ret = samgrProxy->UnloadSystemAbility(DevAttestInterface::SA_ID_DEVICE_ATTEST_SERVICE);
        if (ret != DEVATTEST_SUCCESS) {
            HILOGE("[unload] system ability failed");
            return;
        }
    };

    unloadHandler_->RemoveTask(std::string(ATTEST_UNLOAD_TASK_ID));
    unloadHandler_->PostTask(task, std::string(ATTEST_UNLOAD_TASK_ID), DELAY_TIME);
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
    int32_t resultArraySize = MAX_ATTEST_RESULT_SIZE * sizeof(int32_t);
    int32_t *resultArray = (int32_t *)malloc(resultArraySize);
    if (resultArray == NULL) {
        HILOGE("[GetAttestStatus] malloc resultArray failed");
        return DEVATTEST_FAIL;
    }
    (void)memset_s(resultArray, resultArraySize, 0, resultArraySize);
    int32_t ticketLength = 0;
    char* ticketStr = NULL;
    int32_t ret = DEVATTEST_SUCCESS;
    do {
        ret = QueryAttest(&resultArray, MAX_ATTEST_RESULT_SIZE, &ticketStr, &ticketLength);
        if (ret != DEVATTEST_SUCCESS) {
            HILOGE("[GetAttestStatus] QueryAttest failed");
            break;
        }

        attestResultInfo.ticketLength_ = ticketLength;
        attestResultInfo.ticket_ = ticketStr;
        ret = CopyAttestResult(resultArray, attestResultInfo);
        if (ret != DEVATTEST_SUCCESS) {
            HILOGE("[GetAttestStatus] copy attest result failed");
            break;
        }
    } while (0);
    if (ticketStr != NULL && ticketLength != 0) {
        free(ticketStr);
        ticketStr = NULL;
    }
    free(resultArray);
    resultArray = NULL;
    HILOGD("[GetAttestStatus] GetAttestStatus end");
    return ret;
}
} // end of DevAttest
} // end of OHOS