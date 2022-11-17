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
#include <iostream>

#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "system_ability.h"
#include "singleton.h"

#include "devattest_log.h"
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
    HILOGI("attestResultInfo authResult_ %{public}d", attestResultInfo.authResult_);
    HILOGI("attestResultInfo softwareResult_ %{public}d", attestResultInfo.softwareResult_);
    HILOGI("attestResultInfo ticket_ %{public}s", attestResultInfo.ticket_.c_str());

    int res = DelayedSingleton<DevAttestClient>::GetInstance()->GetAttestStatus(attestResultInfo);

    HILOGI("attestResultInfo authResult_ %{public}d", attestResultInfo.authResult_);
    HILOGI("attestResultInfo softwareResult_ %{public}d", attestResultInfo.softwareResult_);
    HILOGI("attestResultInfo ticket_ %{public}s", attestResultInfo.ticket_.c_str());

    HILOGI("Test client GetAuthRes = %{public}d", res);
    return 0;
}