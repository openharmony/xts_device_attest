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

#include "devattest_service_proxy.h"

#include "devattest_log.h"
#include "devattest_errno.h"
#include "attest_result_info.h"

using namespace std;
namespace OHOS {
namespace DevAttest {
int32_t DevAttestServiceProxy::GetAttestStatus(AttestResultInfo &attestResultInfo)
{
    HILOGI("DevAttestServiceProxy GetAttestStatus begin");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        HILOGE("GetAttestStatus write interface token failed");
        return DEVATTEST_FAIL;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote service null");
        return DEVATTEST_FAIL;
    }
    int ret = remote->SendRequest(GET_AUTH_RESULT, data, reply, option);
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("GetAttestStatus: call SendRequest failed %{public}d", ret);
        return DEVATTEST_FAIL;
    }
    int32_t authRet;
    if (!reply.ReadInt32(authRet)) {
        HILOGE("GetAttestStatus: authRet failed %{public}d", authRet);
        return DEVATTEST_FAIL;
    }
    if (authRet != DEVATTEST_SUCCESS) {
        HILOGE("GetAttestStatus: authRet failed code %{public}d", authRet);
        return authRet;
    }

    sptr<AttestResultInfo> attestResultInfoPtr = AttestResultInfo::Unmarshalling(reply);
    if (attestResultInfoPtr == nullptr) {
        HILOGE("GetAttestStatus: attestResultInfoPtr is nullptr");
        return DEVATTEST_FAIL;
    }
    attestResultInfo = *attestResultInfoPtr;
    return DEVATTEST_SUCCESS;
}
}
}