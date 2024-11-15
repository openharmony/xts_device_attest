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

    int32_t ret = NetConnClient::GetInstance().RegisterNetConnCallback(netCallback_);
    if (ret != NETMANAGER_SUCCESS) {
        HILOGE("[RegisterNetConnCallback] RegisterNetConnCallback failed.");
        return;
    }
}

void DevAttestNetworkManager::UnregisterNetConnCallback(void)
{
    if (netCallback_ == NULL) {
        return;
    }

    int32_t ret = NetConnClient::GetInstance().UnregisterNetConnCallback(netCallback_);
    if (ret != NETMANAGER_SUCCESS) {
        HILOGE("[UnregisterNetConnCallback] RegisterNetConnCallback failed.");
        return;
    }
}
} // DevAttest
} // OHOS