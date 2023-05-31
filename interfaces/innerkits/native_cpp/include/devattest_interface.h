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

#ifndef DEVATTEST_INTERFACE_H
#define DEVATTEST_INTERFACE_H

#include "iremote_broker.h"
#include "attest_result_info.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DevAttest {
class DevAttestInterface : public OHOS::IRemoteBroker {
public:
    static const int SA_ID_DEVICE_ATTEST_SERVICE = DEVICE_ATTEST_PROFILE_SA_ID;
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.devattest.accessToken");

    virtual int32_t GetAttestStatus(AttestResultInfo &attestResultInfo) = 0;

    enum {
        GET_AUTH_RESULT = 0,
        ATTEST_INTERFACE_TYPE_BUTT,
    };
};
} // end of DevAttest
} // end of OHOS
#endif