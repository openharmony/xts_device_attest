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

#ifndef DEVATTEST_CLIENT_H
#define DEVATTEST_CLIENT_H

#include <string>
#include "iremote_object.h"
#include "devattest_interface.h"
#include "singleton.h"

namespace OHOS {
namespace DevAttest {
class DevAttestClient {
    DECLARE_DELAYED_SINGLETON(DevAttestClient)

public:
    int GetAttestStatus(AttestResultInfo &attestResultInfo);

private:
    DevAttestClient(const DevAttestClient&);
    DevAttestClient& operator=(const DevAttestClient&);
    int InitClientService();

    sptr<DevAttestInterface> attestClientInterface_;
};
} // end of DevAttest
} // end of OHOS
#endif