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
#ifndef DEVATTEST_NAPI__H
#define DEVATTEST_NAPI__H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#define PARAM1 1

namespace OHOS {
namespace DevAttest {
class DevAttestNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
private:
    DevAttestNapi() = default;
    ~DevAttestNapi() = default;
    static napi_value GetAttestResultInfo(napi_env env, napi_callback_info info);
    static napi_value GetAttestResultInfoSync(napi_env env, napi_callback_info info);
};
} // namespace DevAttest
} // namespace OHOS

#endif // DEVATTEST_NAPI__H
