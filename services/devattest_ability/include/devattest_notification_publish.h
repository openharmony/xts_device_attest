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

#ifndef DEVATTEST_NOTIFICATION_PUBLISH_H
#define DEVATTEST_NOTIFICATION_PUBLISH_H

#include "resource_manager.h"
#include "singleton.h"

namespace OHOS {
namespace DevAttest {
class DevAttestNotificationPublish {
    DECLARE_DELAYED_SINGLETON(DevAttestNotificationPublish)
public:
    void PublishNotification(void);

private:
    DevAttestNotificationPublish(const DevAttestNotificationPublish&);
    DevAttestNotificationPublish& operator=(const DevAttestNotificationPublish&);
    int32_t GetDevattestBundleUid(int32_t *uid);
    int32_t GetDevattestContent(std::string &title, std::string &text);
    int32_t PublishNotificationImpl(void);
    std::shared_ptr<Global::Resource::ResConfig> GetDevattestResConfig(void);
};
} // DevAttest
} // OHOS
#endif // DEVATTEST_NOTIFICATION_PUBLISH_H