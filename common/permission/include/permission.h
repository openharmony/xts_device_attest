/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef PERMISSION_H
#define PERMISSION_H

#include <string>
#include "singleton.h"

namespace OHOS {
namespace DevAttest {
class Permission {
    DECLARE_DELAYED_SINGLETON(Permission)
public:
    bool IsSystem();
    bool IsPermissionGranted(const std::string& perm);
};
} // namespace DevAttest
} // namespace OHOS
#endif // PERMISSION_H
