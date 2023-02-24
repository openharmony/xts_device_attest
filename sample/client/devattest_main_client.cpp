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

#include <string>

#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "system_ability.h"
#include "singleton.h"

#include "devattest_log.h"
#include "devattest_errno.h"
#include "attest_result_info.h"

using namespace OHOS;
using namespace OHOS::DevAttest;
int main(int argc, char *arg[])
{
    HILOGI("Test client main begin");

    AttestResultInfo attestResultInfo;
    attestResultInfo.authResult_ = 3;
    attestResultInfo.softwareResult_ = 3;
    attestResultInfo.ticket_ = "test";
    attestResultInfo.ticketLength_ = strlen("test");
    HILOGI("attestResultInfo authResult %{public}d", attestResultInfo.authResult_);
    HILOGI("attestResultInfo softwareResult %{public}d", attestResultInfo.softwareResult_);
    HILOGI("attestResultInfo ticket %{public}s", attestResultInfo.ticket_.c_str());

    int res = DelayedSingleton<DevAttestClient>::GetInstance()->GetAttestStatus(attestResultInfo);
    HILOGI("Test client GetAuthRes = %{public}d", res);
    if (res != DEVATTEST_SUCCESS) {
        HILOGI("AttestTest client main fail!");
        return DEVATTEST_FAIL;
    }
    HILOGI("attestResultInfo authResult %{public}d", attestResultInfo.authResult_);
    HILOGI("attestResultInfo softwareResult %{public}d", attestResultInfo.softwareResult_);
    HILOGI("attestResultInfo ticket %{public}s", attestResultInfo.ticket_.c_str());
    HILOGI("attestResultInfo ticketLength %{public}d", attestResultInfo.ticketLength_);
    HILOGI("attestResultInfo softwareResultDetail");
    for (int i = 0; i < SOFTWARE_RESULT_DETAIL_SIZE; i++) {
        HILOGI("[%{public}d] %{public}d", i, attestResultInfo.softwareResultDetail_[i]);
    }

    HILOGI("Test client main end");
    return DEVATTEST_SUCCESS;
}