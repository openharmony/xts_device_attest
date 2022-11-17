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

#ifndef DEVATTEST_SERVICE_PROXY_H
#define DEVATTEST_SERVICE_PROXY_H

#include <string>
#include "iremote_proxy.h"
#include "devattest_interface.h"

namespace OHOS {
namespace DevAttest {
class DevAttestServiceProxy : public IRemoteProxy<DevAttestInterface> {
public:
    explicit DevAttestServiceProxy(const sptr<IRemoteObject> &impl)
        : IRemoteProxy<DevAttestInterface>(impl) {}
    ~DevAttestServiceProxy() {}

    int32_t GetAttestStatus(AttestResultInfo &attestResultInfo) override;
private:
    static inline BrokerDelegator<DevAttestServiceProxy> delegator_;
};
} // end of DevAttest
} // end of OHOS
#endif