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

#include "devattest_task.h"

#include <pthread.h>
#include "iservice_registry.h"
#include "singleton.h"
#include "devattest_log.h"
#include "devattest_errno.h"
#include "devattest_notification_publish.h"
#include "attest_entry.h"

namespace OHOS {
namespace DevAttest {
using namespace OHOS;

constexpr std::int32_t SA_ID_DEVICE_ATTEST_SERVICE = 5501;
const char* ATTEST_RUN_TASK_ID = "attest_run";
DevAttestTask::DevAttestTask()
{
}

DevAttestTask::~DevAttestTask()
{
}

bool DevAttestTask::CreateThread()
{
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    int priority = 0;
    struct sched_param sched = {static_cast<int>(priority)};
    pthread_attr_setschedparam(&attr, &sched);
    int ret = pthread_create(&tid, &attr, DevAttestTask::Run, NULL);
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("thread create failed, ret: %{public}d", ret);
        return false;
    }
    return true;
}

void* DevAttestTask::Run(void* arg)
{
    (void)pthread_setname_np(pthread_self(), ATTEST_RUN_TASK_ID); // set pthread name, at most 15 bytes.
    (void)AttestTask();
    DelayedSingleton<DevAttestNotificationPublish>::GetInstance()->PublishNotification();
    UnloadTask();
    HILOGI("Thread exited...");
    return nullptr;
}

void DevAttestTask::UnloadTask(void)
{
    sptr<ISystemAbilityManager> samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOGE("get samgr failed");
        return;
    }
    int32_t ret = samgrProxy->UnloadSystemAbility(SA_ID_DEVICE_ATTEST_SERVICE);
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("remove system ability failed");
        return;
    }
}
} // end of DevAttest
} // end of OHOS