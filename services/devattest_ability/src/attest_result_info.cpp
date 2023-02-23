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
#include "attest_result_info.h"

namespace OHOS {
namespace DevAttest {
bool AttestResultInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(authResult_) || !parcel.WriteInt32(softwareResult_)) {
        return false;
    }
    if (!parcel.WriteInt32(softwareResultDetail_.size()) || !parcel.WriteInt32Vector(softwareResultDetail_)) {
        return false;
    }
    if (!parcel.WriteInt32(ticketLength_) || !parcel.WriteString(ticket_)) {
        return false;
    }
    return true;
}

sptr<AttestResultInfo> AttestResultInfo::Unmarshalling(Parcel &parcel)
{
    sptr<AttestResultInfo> ptr = (std::make_unique<AttestResultInfo>()).release();
    if (ptr == nullptr) {
        return nullptr;
    }
    if (!parcel.ReadInt32(ptr->authResult_) || !parcel.ReadInt32(ptr->softwareResult_)) {
        return nullptr;
    }
    int32_t setCount;
    if (!parcel.ReadInt32(setCount) || setCount != SOFTWARE_RESULT_DETAIL_SIZE) {
        return nullptr;
    }

    ptr->softwareResultDetail_.resize(setCount);
    parcel.ReadInt32Vector(&ptr->softwareResultDetail_);

    if (!parcel.ReadInt32(ptr->ticketLength_) || !parcel.ReadString(ptr->ticket_)) {
        return nullptr;
    }
    return ptr;
}
}
}