/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef DEVATTEST_NETWORK_MANAGER_H
#define DEVATTEST_NETWORK_MANAGER_H


#include "singleton.h"
#include "devattest_network_callback.h"

namespace OHOS {
namespace DevAttest {
class DevAttestNetworkManager {
    DECLARE_DELAYED_SINGLETON(DevAttestNetworkManager)
public:
    void RegisterNetConnCallback(void);
    void UnregisterNetConnCallback(void);
private:
    sptr<DevAttestNetworkCallback> netCallback_;
};
} // DevAttest
} // OHOS
#endif // DEVATTEST_NETWORK_MANAGER_H