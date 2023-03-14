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
#include <stdio.h>

#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "system_ability.h"
#include "singleton.h"

#include "devattest_errno.h"
#include "attest_result_info.h"

using namespace OHOS;
using namespace OHOS::DevAttest;
int main(int argc, char *arg[])
{
    printf("[DEVATTEST]Test client main begin\n");
    AttestResultInfo attestResultInfo;
    attestResultInfo.authResult_ = 3;
    attestResultInfo.softwareResult_ = 3;
    attestResultInfo.ticket_ = "test";
    attestResultInfo.ticketLength_ = strlen("test");

    int res = DelayedSingleton<DevAttestClient>::GetInstance()->GetAttestStatus(attestResultInfo);
    if (res != DEVATTEST_SUCCESS) {
        printf("[DEVATTEST]AttestTest client main fail!\n");
        return DEVATTEST_FAIL;
    }
    printf("[DEVATTEST]attestResultInfo authResult %d\n", attestResultInfo.authResult_);
    printf("[DEVATTEST]attestResultInfo softwareResult %d\n", attestResultInfo.softwareResult_);
    printf("[DEVATTEST]attestResultInfo ticket %s\n", attestResultInfo.ticket_.c_str());
    printf("[DEVATTEST]attestResultInfo ticketLength %d\n", attestResultInfo.ticketLength_);

    for (int i = 0; i < SOFTWARE_RESULT_DETAIL_SIZE; i++) {
        printf("[DEVATTEST]attestResultInfo softwareResultDetail[%d] %d\n",
            i, attestResultInfo.softwareResultDetail_[i]);
    }
    printf("[DEVATTEST]Test client main ended successfully!\n");
    return DEVATTEST_SUCCESS;
}