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

#ifndef DEVATTEST_LOG_H
#define DEVATTEST_LOG_H

#include <string>

#include "hilog/log.h"

namespace OHOS {
namespace DevAttest {
static constexpr OHOS::HiviewDFX::HiLogLabel DEVATTEST_LABEL = {LOG_CORE, 0xD001800, "DEVATTEST"};

#define HILOGF(...) (void)OHOS::HiviewDFX::HiLog::Fatal(DEVATTEST_LABEL, ##__VA_ARGS__)
#define HILOGE(...) (void)OHOS::HiviewDFX::HiLog::Error(DEVATTEST_LABEL, ##__VA_ARGS__)
#define HILOGW(...) (void)OHOS::HiviewDFX::HiLog::Warn(DEVATTEST_LABEL, ##__VA_ARGS__)
#define HILOGI(...) (void)OHOS::HiviewDFX::HiLog::Info(DEVATTEST_LABEL, ##__VA_ARGS__)
#define HILOGD(...) (void)OHOS::HiviewDFX::HiLog::Debug(DEVATTEST_LABEL, ##__VA_ARGS__)
} // end of DevAttest
} // end of OHOS
#endif