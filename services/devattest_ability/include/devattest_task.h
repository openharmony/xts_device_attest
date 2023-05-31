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

#ifndef DEVATTEST_TASK_H
#define DEVATTEST_TASK_H

// #include <string>
// #include <map>
// #include "iremote_stub.h"
// #include "iremote_object.h"
// #include "system_ability.h"
// #include "system_ability_ondemand_reason.h"
// #include "system_ability_status_change_stub.h"
// #include "devattest_interface.h"
// #include "devattest_service_stub.h"
// #include "attest_result_info.h"

// #include <pthread.h>
// #include <functional>
// #include "resource_manager.h"

namespace OHOS {
namespace DevAttest {
class DevAttestTask {
public:
    DevAttestTask();
    ~DevAttestTask();
    bool CreateThread();

private:
    static void* Run(void* arg);
    static void UnloadTask(void);
};
} // end of DevAttest
} // end of OHOS
#endif