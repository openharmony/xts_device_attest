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

#include "devattest_service_stub.h"

#include "system_ability_definition.h"
#include "iremote_object.h"
#include "iremote_stub.h"
#include "iservice_registry.h"
#include "permission.h"
#include "devattest_log.h"
#include "devattest_errno.h"
#include "attest_result_info.h"

namespace OHOS {
namespace DevAttest {
DevAttestServiceStub::DevAttestServiceStub()
{
    requestFuncMap_[GET_AUTH_RESULT] = &DevAttestServiceStub::GetAttestStatusInner;
}

DevAttestServiceStub::~DevAttestServiceStub()
{
    requestFuncMap_.clear();
}

int DevAttestServiceStub::OnRemoteRequest(uint32_t code,
    MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    HILOGD("DevAttestServiceStub::OnRemoteRequest, cmd = %{public}d, flags = %{public}d", code, option.GetFlags());
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        HILOGE("DevAttestServiceStub::OnRemoteRequest failed, descriptor is not matched!");
        return DEVATTEST_SERVICE_FAILED;
    }
    auto itFunc = requestFuncMap_.find(code);
    if (itFunc != requestFuncMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return (this->*requestFunc)(data, reply);
        }
    }
    HILOGE("DevAttestServiceStub::OnRemoteRequest, default case");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int DevAttestServiceStub::GetAttestStatusInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("DevAttestServiceStub::GetAttestStatusInner");
    if (!DelayedSingleton<Permission>::GetInstance()->IsSystem()) {
        HILOGE("GetAttestStatusInner: not a system");
        if (!reply.WriteInt32(DEVATTEST_ERR_JS_IS_NOT_SYSTEM_APP)) {
            HILOGE("GetAttestStatusInner: write DEVATTEST_ERR_JS_IS_NOT_SYSTEM_APP fail");
            return DEVATTEST_FAIL;
        }
        return DEVATTEST_SUCCESS;
    }

    AttestResultInfo attestResultInfo;
    int ret = GetAttestStatus(attestResultInfo);
    if (!reply.WriteInt32(ret)) {
        HILOGE("GetAttestStatusInner: write result fail, %{public}d", ret);
        return DEVATTEST_FAIL;
    }
    if (ret == DEVATTEST_SUCCESS) {
        sptr<AttestResultInfo> attestResultInfoPtr = (std::make_unique<AttestResultInfo>(attestResultInfo)).release();
        if (!attestResultInfoPtr->Marshalling(reply)) {
            HILOGE("GetAttestStatusInner stub Marshalling failed");
            return DEVATTEST_FAIL;
        }
    } else {
        HILOGE("GetAttestStatusInner: GetAttestStatus fail, %{public}d", ret);
        return DEVATTEST_FAIL;
    }
    return DEVATTEST_SUCCESS;
}
} // end of DevAttest
} // end of OHOS