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

#ifndef DEVATTEST_SERVICE_H
#define DEVATTEST_SERVICE_H

#include <string>
#include <map>
#include "system_ability.h"
#include "iremote_stub.h"
#include "iremote_object.h"
#include "singleton.h"

#include "devattest_interface.h"
#include "devattest_service_stub.h"
#include "system_ability_status_change_stub.h"
#include "attest_result_info.h"

namespace OHOS {
namespace DevAttest {
enum class ServiceRunningState {
    STATE_NOT_START,
    STATE_RUNNING
};

class DevAttestService : public SystemAbility, public DevAttestServiceStub {
    DECLARE_SYSTEM_ABILITY(DevAttestService);
    DECLARE_DELAYED_SINGLETON(DevAttestService);

public:
    DevAttestService(int32_t systemAbilityId, bool runOnCreate = true);
    void OnStart() override;
    void OnStop() override;
    ServiceRunningState QueryServiceState() const
    {
        return state_;
    }
    int32_t GetAttestStatus(AttestResultInfo &attestResultInfo) override;

private:
    bool Init();
    ServiceRunningState state_ = ServiceRunningState::STATE_NOT_START;
    bool registerToSa_ = false;
    bool CheckPermission(const std::string &packageName);
    const int32_t NETMANAGER_SAMGR_ID = 1151;
    int32_t CopyAttestResult(int32_t *resultArray, AttestResultInfo &attestResultInfo);
};
} // end of DevAttest
} // end of OHOS
#endif