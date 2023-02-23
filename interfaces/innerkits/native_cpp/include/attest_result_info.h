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
#ifndef ATTEST_RESULT_INFO_H
#define ATTEST_RESULT_INFO_H

#include "parcel.h"
#include <string>
#include <list>

#define SOFTWARE_RESULT_DETAIL_SIZE 5

typedef enum {
    ATTEST_RESULT_AUTH = 0,
    ATTEST_RESULT_SOFTWARE,
    ATTEST_RESULT_VERSIONID,
    ATTEST_RESULT_PATCHLEVEL,
    ATTEST_RESULT_ROOTHASH,
    ATTEST_RESULT_PCID,
    ATTEST_RESULT_MAX,
} ATTEST_RESULT_INFO_TYPE; // Modify ATTEST_RESULT_TYPE at the same time

namespace OHOS {
namespace DevAttest {
class AttestResultInfo : public Parcelable {
public:
    int32_t authResult_ = -1;
    int32_t softwareResult_ = -1;
    std::vector<int32_t> softwareResultDetail_ = {-1, -1, -1, -1, -1};
    int32_t ticketLength_ = 0;
    std::string ticket_;

    virtual bool Marshalling(Parcel &parcel) const override;
    static sptr<AttestResultInfo> Unmarshalling(Parcel &parcel);
};
} // end of DevAttest
} // end of OHOS
#endif