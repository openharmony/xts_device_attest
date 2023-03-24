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

#ifndef DEVATTEST_ERRNO_H
#define DEVATTEST_ERRNO_H

#include <errors.h>

namespace OHOS {
    namespace DevAttest {
        enum {
            DEVATTEST_INIT = -2,

            DEVATTEST_FAIL = -1,

            DEVATTEST_SUCCESS = 0,

            DEVATTEST_ERR_JS_IS_NOT_SYSTEM_APP = 202,
            DEVATTEST_ERR_JS_PARAMETER_ERROR = 401,
            DEVATTEST_ERR_JS_SYSTEM_SERVICE_EXCEPTION = 20000001,
            // SA框架使用错误码
            DEVATTEST_SERVICE_FAILED = 0x10000 + 1,
            DEVATTEST_WRITE_FAIL = 0x10000 + 2,
            DEVATTEST_PARAM_NULL,
            DEVATTEST_SA_NO_INIT,
        };
    } // end of DevAttest
} // end of OHOS
#endif