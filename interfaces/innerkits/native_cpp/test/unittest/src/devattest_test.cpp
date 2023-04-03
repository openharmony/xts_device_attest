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

#include "devattest_client_test.h"

#include "devattest_errno.h"
#include "attest_result_info.h"
#include "devattest_client.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DevAttest;

namespace OHOS {
namespace DevAttest {
static bool AttestStatusNumberValid(int32_t attestStatusNumber)
{
    if (attestStatusNumber < DEVATTEST_INIT || attestStatusNumber > DEVATTEST_SUCCESS) {
        return false;
    }
    return true;
}

::testing::AssertionResult AttestStatusValid(AttestResultInfo attestResultInfo)
{
    bool result = true;
    string failString;
    if (!AttestStatusNumberValid(attestResultInfo.authResult_)) {
        failString += string(" authResult is ") + to_string(attestResultInfo.authResult_);
        result = false;
    }
    if (!AttestStatusNumberValid(attestResultInfo.softwareResult_)) {
        failString += string(" softwareResult is ") + to_string(attestResultInfo.softwareResult_);
        result = false;
    }
    vector<int32_t> softwareResultArray = attestResultInfo.softwareResultDetail_;
    if (!AttestStatusNumberValid(softwareResultArray[SOFTWARE_RESULT_VERSIONID])) {
        failString += string(" versionResult is ") + to_string(softwareResultArray[SOFTWARE_RESULT_VERSIONID]);
        result = false;
    }
    if (!AttestStatusNumberValid(softwareResultArray[SOFTWARE_RESULT_PATCHLEVEL])) {
        failString += string(" patchResult is ") + to_string(softwareResultArray[SOFTWARE_RESULT_PATCHLEVEL]);
        result = false;
    }
    if (!AttestStatusNumberValid(softwareResultArray[SOFTWARE_RESULT_ROOTHASH])) {
        failString += string(" roothashResult is ") + to_string(softwareResultArray[SOFTWARE_RESULT_ROOTHASH]);
        result = false;
    }
    if (!AttestStatusNumberValid(softwareResultArray[SOFTWARE_RESULT_PCID])) {
        failString += string(" pcidResult is ") + to_string(softwareResultArray[SOFTWARE_RESULT_PCID]);
        result = false;
    }
    if (!AttestStatusNumberValid(softwareResultArray[SOFTWARE_RESULT_RESERVE])) {
        failString += string(" reserveResult is ") + to_string(softwareResultArray[SOFTWARE_RESULT_PCID]);
        result = false;
    }
    if (attestResultInfo.authResult_ == DEVATTEST_SUCCESS) {
        if (attestResultInfo.ticketLength_ <= 0) {
            failString += string(" ticketLength is ") + to_string(attestResultInfo.ticketLength_);
            result = false;
        }
        if (attestResultInfo.ticket_.empty()) {
            failString += string(" ticket is empty");
            result = false;
        }
    }
    if (result) {
        return ::testing::AssertionSuccess();
    } else {
        return ::testing::AssertionFailure() << failString.c_str();
    }
}
} // namespace DevAttest
} // namespace OHOS
