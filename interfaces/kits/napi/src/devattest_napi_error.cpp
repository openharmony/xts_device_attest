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

#include <unordered_map>
#include "devattest_errno.h"
#include "devattest_napi_error.h"

namespace OHOS {
namespace DevAttest {
static const std::unordered_map<uint32_t, std::string> g_errorStringMap = {
    {DEVATTEST_ERR_JS_IS_NOT_SYSTEM_APP,
        "This api is system api, Please use the system application to call this api"},
    {DEVATTEST_ERR_JS_PARAMETER_ERROR, "Input paramters wrong"},
    {DEVATTEST_ERR_JS_SYSTEM_SERVICE_EXCEPTION, "System service exception, please try again or reboot your device"},
};

int32_t ConvertToJsErrCode(int32_t errCode)
{
    int32_t jsErrCode = errCode;
    if (jsErrCode == DEVATTEST_FAIL) {
        jsErrCode = DEVATTEST_ERR_JS_SYSTEM_SERVICE_EXCEPTION;
    }
    return jsErrCode;
}

std::string ConvertToJsErrMsg(int32_t jsErrCode)
{
    auto iter = g_errorStringMap.find(jsErrCode);
    if (iter != g_errorStringMap.end()) {
        return iter->second;
    } else {
        return "Unknown error, please reboot your device and try again";
    }
}
} // namespace DevAttest
} // namespace OHOS
