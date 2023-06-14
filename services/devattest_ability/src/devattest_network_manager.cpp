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

#include "devattest_network_manager.h"

#include <thread>
#include <cstdint>
#include "net_conn_client.h"
#include "devattest_log.h"
#include "devattest_errno.h"

namespace OHOS {
namespace DevAttest {
DevAttestNetworkManager::DevAttestNetworkManager()
{
}

DevAttestNetworkManager::~DevAttestNetworkManager()
{
}

void DevAttestNetworkManager::RegisterNetConnCallback(void)
{
    if (netCallback_ == NULL) {
        netCallback_ = (std::make_unique<DevAttestNetworkCallback>()).release();
    }
    std::shared_ptr<NetManagerStandard::NetConnClient> netManager = DelayedSingleton<NetConnClient>::GetInstance();
    if (netManager == nullptr) {
        HILOGE("[OnAddSystemAbility] Failed to init NetConnClient.");
        return;
    }

    int32_t ret = netManager->RegisterNetConnCallback(netCallback_);
    if (ret != NETMANAGER_SUCCESS) {
        HILOGE("[OnAddSystemAbility] RegisterNetConnCallback failed.");
        return;
    }
}

void DevAttestNetworkManager::UnregisterNetConnCallback(void)
{
    if (netCallback_ == NULL) {
        return;
    }
    std::shared_ptr<NetManagerStandard::NetConnClient> netManager = DelayedSingleton<NetConnClient>::GetInstance();
    if (netManager == nullptr) {
        HILOGE("[OnAddSystemAbility] Failed to init NetConnClient.");
        return;
    }

    int32_t ret = netManager->UnregisterNetConnCallback(netCallback_);
    if (ret != NETMANAGER_SUCCESS) {
        HILOGE("[OnAddSystemAbility] RegisterNetConnCallback failed.");
        return;
    }
}
} // DevAttest
} // OHOS