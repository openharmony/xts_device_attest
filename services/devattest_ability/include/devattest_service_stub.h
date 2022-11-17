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

#ifndef DEVATTEST_SERVICE_STUB_H
#define DEVATTEST_SERVICE_STUB_H

#include <string>
#include <map>
#include "iremote_stub.h"
#include "iremote_object.h"
#include "devattest_interface.h"

namespace OHOS {
namespace DevAttest {
class DevAttestServiceStub : public IRemoteStub<DevAttestInterface> {
public:
    DevAttestServiceStub();
    ~DevAttestServiceStub();
    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:
    int GetAttestStatusInner(MessageParcel& data, MessageParcel& reply);
    using RequestFuncType = int (DevAttestServiceStub::*)(MessageParcel& data, MessageParcel& reply);
    std::map<uint32_t, RequestFuncType> requestFuncMap_;
};
} // end of DevAttest
} // end of OHOS
#endif